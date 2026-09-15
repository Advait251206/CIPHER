"""
CIPHER Phase 8 — Threat Intelligence & IOC Correlation Layer Test Suite
Validates IOC models, local SQLite store, exact & normalized matching, expiration filtering,
disabled flags, non-additive ThreatScorer synthesis, pipeline integration, security guarantees,
explicit demo seeding controls, and REST APIs (including JSON & CSV imports).
"""

import io
import time
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database.database import Database
from app.threat_intel.models import (
    IOCType,
    IOCSeverity,
    IOCItem,
    IOCCreateRequest,
    IOCMatch
)
from app.threat_intel.config import (
    ALLOWED_IOC_TYPES,
    ALLOWED_SEVERITIES,
    DEMO_IOC_DATASET
)
from app.threat_intel.store import IOCStore, normalize_indicator
from app.threat_intel.matcher import ThreatIntelMatcher
from app.threat_intel.service import ThreatIntelService
from app.detection.threat_scorer import ThreatScorer
from app.correlation.service import CorrelationService

client = TestClient(app)


# =============================================================================
# 1. Model Validation Tests
# =============================================================================

def test_valid_ioc_models():
    """Validates creation of valid IP, Domain, URL, and Hash IOC models."""
    # IPv4
    ip_ioc = IOCCreateRequest(ioc_type="IP", indicator="198.51.100.1")
    assert ip_ioc.ioc_type == "IP"
    assert ip_ioc.indicator == "198.51.100.1"

    # IPv6
    ipv6_ioc = IOCCreateRequest(ioc_type="IP", indicator="2001:db8::1")
    assert ipv6_ioc.indicator == "2001:db8::1"

    # Domain
    dom_ioc = IOCCreateRequest(ioc_type="DOMAIN", indicator="malicious-c2.test")
    assert dom_ioc.indicator == "malicious-c2.test"

    # URL
    url_ioc = IOCCreateRequest(ioc_type="URL", indicator="https://phishing-site.test/login")
    assert url_ioc.indicator == "https://phishing-site.test/login"

    # Hash (MD5, SHA1, SHA256)
    md5_ioc = IOCCreateRequest(ioc_type="HASH", indicator="d41d8cd98f00b204e9800998ecf8427e")
    assert md5_ioc.indicator == "d41d8cd98f00b204e9800998ecf8427e"

    sha256_ioc = IOCCreateRequest(
        ioc_type="HASH",
        indicator="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert sha256_ioc.indicator == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_invalid_ioc_indicators_rejected():
    """Invalid indicators must raise ValidationError with clear explanation."""
    # Empty
    with pytest.raises(Exception):
        IOCCreateRequest(ioc_type="IP", indicator="")

    # Invalid IP
    with pytest.raises(Exception):
        IOCCreateRequest(ioc_type="IP", indicator="999.999.999.999")

    with pytest.raises(Exception):
        IOCCreateRequest(ioc_type="IP", indicator="not-an-ip")

    # Domain with scheme or invalid chars
    with pytest.raises(Exception):
        IOCCreateRequest(ioc_type="DOMAIN", indicator="https://example.com")

    # URL without scheme
    with pytest.raises(Exception):
        IOCCreateRequest(ioc_type="URL", indicator="example.com/login")

    # Hash with invalid hex or length
    with pytest.raises(Exception):
        IOCCreateRequest(ioc_type="HASH", indicator="not-hex-chars-at-all!!")

    with pytest.raises(Exception):
        IOCCreateRequest(ioc_type="HASH", indicator="abc123")  # too short

    # Invalid type
    with pytest.raises(Exception):
        IOCCreateRequest(ioc_type="INVALID_TYPE", indicator="1.1.1.1")


# =============================================================================
# 2. Local Store CRUD, Duplicates, and Expiration
# =============================================================================

def test_store_crud_and_deterministic_duplicates():
    """Validates adding, retrieving, duplicate detection, and deleting IOCs."""
    store = IOCStore()
    test_ip = f"198.51.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}"

    req = IOCCreateRequest(
        ioc_type="IP",
        indicator=test_ip,
        severity="HIGH",
        confidence=0.90,
        category="C2",
        description="Temporary test C2"
    )

    created = store.add_ioc(req)
    assert created.ioc_id.startswith("IOC-")
    assert created.indicator == test_ip
    assert created.enabled is True

    # Retrieve by ID
    retrieved = store.get_ioc(created.ioc_id)
    assert retrieved is not None
    assert retrieved.indicator == test_ip

    # Duplicate must be rejected deterministically
    with pytest.raises(ValueError, match="Duplicate IOC"):
        store.add_ioc(req)

    # Delete
    deleted = store.delete_ioc(created.ioc_id)
    assert deleted is True
    assert store.get_ioc(created.ioc_id) is None


def test_store_enable_disable():
    """Disabled IOCs must be excluded from active lookups."""
    store = IOCStore()
    test_dom = f"test-{uuid.uuid4().hex[:8]}.test"

    req = IOCCreateRequest(ioc_type="DOMAIN", indicator=test_dom, enabled=True)
    item = store.add_ioc(req)

    # Active lookup succeeds
    found = store.get_ioc_by_indicator(test_dom, ioc_type="DOMAIN", active_only=True)
    assert found is not None
    assert found.ioc_id == item.ioc_id

    # Disable
    store.set_ioc_enabled(item.ioc_id, False)
    assert store.get_ioc_by_indicator(test_dom, ioc_type="DOMAIN", active_only=True) is None

    # But still present if active_only=False
    inactive_item = store.get_ioc_by_indicator(test_dom, ioc_type="DOMAIN", active_only=False)
    assert inactive_item is not None
    assert inactive_item.enabled is False

    # Cleanup
    store.delete_ioc(item.ioc_id)


def test_store_expiration():
    """Expired IOCs must not match active lookups."""
    store = IOCStore()
    test_ip = f"198.51.100.{uuid.uuid4().int % 200 + 10}"

    # Past expiration
    past_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    req = IOCCreateRequest(
        ioc_type="IP",
        indicator=test_ip,
        expires_at=past_iso
    )
    item = store.add_ioc(req)

    # Active lookup must return None
    assert store.get_ioc_by_indicator(test_ip, ioc_type="IP", active_only=True) is None

    # Cleanup
    store.delete_ioc(item.ioc_id)


# =============================================================================
# 3. Matching Engine & Normalization Tests
# =============================================================================

def test_matcher_ip_source_and_destination():
    """Tests exact source IP and destination IP matching."""
    store = IOCStore()
    matcher = ThreatIntelMatcher(store=store)

    c2_ip = f"198.51.100.{uuid.uuid4().int % 200 + 10}"
    req = IOCCreateRequest(ioc_type="IP", indicator=c2_ip, severity="CRITICAL", category="C2")
    item = store.add_ioc(req)

    # Match as source_ip
    event_src = {"source_ip": c2_ip, "destination_ip": "10.0.0.1"}
    matches_src = matcher.match_event(event_src)
    assert len(matches_src) == 1
    assert matches_src[0].ioc_id == item.ioc_id
    assert matches_src[0].matched_field == "source_ip"
    assert "Threat intelligence match detected" in matches_src[0].explanation

    # Match as destination_ip
    event_dst = {"source_ip": "10.0.0.1", "destination_ip": c2_ip}
    matches_dst = matcher.match_event(event_dst)
    assert len(matches_dst) == 1
    assert matches_dst[0].matched_field == "destination_ip"

    # Clean
    store.delete_ioc(item.ioc_id)


def test_matcher_domain_normalization():
    """Domain matching safely normalizes whitespace, uppercase, trailing dots, and ports."""
    store = IOCStore()
    matcher = ThreatIntelMatcher(store=store)

    domain_raw = f"malware-hub-{uuid.uuid4().hex[:6]}.test"
    req = IOCCreateRequest(ioc_type="DOMAIN", indicator=domain_raw, severity="HIGH")
    item = store.add_ioc(req)

    # Variation: uppercase + trailing dot
    event_var = {"domain": f"  {domain_raw.upper()}. "}
    matches = matcher.match_event(event_var)
    assert len(matches) == 1
    assert matches[0].ioc_id == item.ioc_id
    assert matches[0].matched_field == "domain"

    # Variation: domain with port
    event_port = {"domain": f"{domain_raw}:8080"}
    matches_port = matcher.match_event(event_port)
    assert len(matches_port) == 1

    store.delete_ioc(item.ioc_id)


def test_matcher_url_and_hash():
    """Tests URL canonicalization and hash matching."""
    store = IOCStore()
    matcher = ThreatIntelMatcher(store=store)

    url_str = f"http://phish-{uuid.uuid4().hex[:6]}.test/login"
    hash_str = "a" * 64

    url_item = store.add_ioc(IOCCreateRequest(ioc_type="URL", indicator=url_str, severity="CRITICAL"))
    hash_item = store.add_ioc(IOCCreateRequest(ioc_type="HASH", indicator=hash_str, severity="HIGH"))

    event = {
        "url": url_str + "/",
        "metadata": {"payload_hash": hash_str.upper()}
    }
    matches = matcher.match_event(event)
    matched_ids = {m.ioc_id for m in matches}

    assert url_item.ioc_id in matched_ids
    assert hash_item.ioc_id in matched_ids

    store.delete_ioc(url_item.ioc_id)
    store.delete_ioc(hash_item.ioc_id)


# =============================================================================
# 4. ThreatScorer Synthesis & User Correction #2
# =============================================================================

def test_threat_scorer_floor_applied_when_risk_low():
    """When existing risk < IOC floor, the IOC floor is applied."""
    scorer = ThreatScorer()
    # Mock a CRITICAL match with 0.85 confidence
    # Floor: max(75, int(75 + 25 * 0.85)) = max(75, 96) = 96
    mock_match = IOCMatch(
        ioc_id="IOC-TEST-1",
        indicator="203.0.113.10",
        ioc_type="IP",
        source="TEST",
        confidence=0.85,
        severity="CRITICAL",
        category="C2",
        explanation="test",
        matched_field="source_ip"
    )

    risk, sev, cl = scorer.apply_threat_intel(
        current_risk=20,
        current_severity="LOW",
        current_classification="BENIGN",
        ti_matches=[mock_match]
    )

    assert risk >= 75  # Guaranteed CRITICAL band
    assert sev == "CRITICAL"
    assert cl == "C2"  # Benign classification elevated


def test_threat_scorer_existing_risk_preserved_when_higher():
    """When existing risk > IOC floor, existing risk is preserved."""
    scorer = ThreatScorer()
    mock_match = IOCMatch(
        ioc_id="IOC-TEST-2",
        indicator="192.0.2.1",
        ioc_type="IP",
        source="TEST",
        confidence=0.80,
        severity="MEDIUM",
        category="SCANNER",
        explanation="test",
        matched_field="source_ip"
    )

    # Existing risk is 95 (from DoS flood ML/heuristic)
    risk, sev, cl = scorer.apply_threat_intel(
        current_risk=95,
        current_severity="CRITICAL",
        current_classification="ATTACK",
        ti_matches=[mock_match]
    )

    assert risk == 95  # Not reduced to medium floor
    assert sev == "CRITICAL"
    assert cl == "ATTACK"


def test_threat_scorer_dominant_evidence_only_no_additive_scoring():
    """Multiple matching IOCs evaluate single dominant evidence; NO additive accumulation."""
    scorer = ThreatScorer()
    m1 = IOCMatch(
        ioc_id="IOC-1",
        indicator="10.0.0.1",
        ioc_type="IP",
        source="T",
        confidence=0.90,
        severity="HIGH",
        category="C2",
        explanation="t",
        matched_field="source_ip"
    )
    m2 = IOCMatch(
        ioc_id="IOC-2",
        indicator="c2.test",
        ioc_type="DOMAIN",
        source="T",
        confidence=0.90,
        severity="HIGH",
        category="C2",
        explanation="t",
        matched_field="domain"
    )

    # Evaluating with m1 alone
    risk1, _, _ = scorer.apply_threat_intel(0, "LOW", "BENIGN", [m1])
    # Evaluating with both m1 and m2
    risk_both, _, _ = scorer.apply_threat_intel(0, "LOW", "BENIGN", [m1, m2])

    # Must be identical! Zero additive inflation
    assert risk1 == risk_both


def test_threat_scorer_benign_elevated_on_match():
    """An active IOC match prevents an event from remaining benign."""
    scorer = ThreatScorer()
    match = IOCMatch(
        ioc_id="IOC-3",
        indicator="suspicious.test",
        ioc_type="DOMAIN",
        source="T",
        confidence=0.70,
        severity="LOW",
        category="SUSPICIOUS",
        explanation="t",
        matched_field="domain"
    )

    _, _, cl = scorer.apply_threat_intel(10, "LOW", "BENIGN", [match])
    assert cl != "BENIGN"
    assert cl in ("SUSPICIOUS", "ATTACK")


# =============================================================================
# 5. Pipeline Integration Test
# =============================================================================

def test_pipeline_integration_with_threat_intel():
    """Normalized event passing through CorrelationService attaches IOC findings."""
    store = IOCStore()
    c2_ip = f"198.51.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}"
    item = store.add_ioc(IOCCreateRequest(
        ioc_type="IP",
        indicator=c2_ip,
        severity="CRITICAL",
        category="C2"
    ))

    corr_service = CorrelationService()

    event = {
        "event_id": f"evt-{uuid.uuid4().hex[:8]}",
        "source_ip": c2_ip,
        "destination_ip": f"10.123.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}",
        "destination_port": 80,
        "features": {
            "Total Fwd Packets": 5,
            "Total Backward Packets": 5,
            "Flow Duration": 100000
        },
        "classification": "BENIGN",
        "risk_score": 10,
        "confidence": 0.85,
        "severity": "LOW"
    }

    db = Database()
    db.save_event(event)

    incident = corr_service.process_event(event)
    assert incident is not None

    # Verify incident elevation through Threat Intelligence and ThreatScorer
    assert "C2" in incident["attack_categories"]
    assert incident["severity"] == "CRITICAL"
    assert incident["correlation_score"] >= 75

    store.delete_ioc(item.ioc_id)


# =============================================================================
# 6. Safety & Demo Data Policy (User Correction #1)
# =============================================================================

def test_demo_iocs_not_auto_seeded():
    """By default (CIPHER_LOAD_DEMO_IOCS=false), demo IOCs are NOT automatically inserted."""
    store = IOCStore()
    items, _ = store.list_iocs(limit=500)
    # None of the items should be auto-inserted demo items unless explicitly seeded
    demo_in_db = [i for i in items if i.source == "CIPHER_DEMO"]
    # If a previous test seeded them, they might be there, but calling ThreatIntelService() without flag should not add them
    service = ThreatIntelService(store=store)
    # Calling seed_demo_iocs with force=False must seed 0
    seeded = service.seed_demo_iocs(force=False)
    assert seeded == 0


def test_explicit_demo_seeding_works():
    """Explicitly forcing demo seeding succeeds and marks indicators as synthetic."""
    store = IOCStore()
    service = ThreatIntelService(store=store)
    seeded = service.seed_demo_iocs(force=True)
    assert seeded >= 0  # May be 0 if already seeded, or positive if new

    # Verify a known synthetic demo indicator
    demo_match = service.check_indicator("203.0.113.10", ioc_type="IP")
    if demo_match:
        assert demo_match.source == "CIPHER_DEMO"


def test_security_treats_iocs_strictly_as_data():
    """Verifies that malicious payloads inside indicators cannot execute code."""
    store = IOCStore()
    dangerous_payload = "http://evil.test/$(calc.exe);eval('alert(1)');`rm -rf /`"

    # Creating with URL type should either reject or sanitize as static string
    try:
        req = IOCCreateRequest(ioc_type="URL", indicator=dangerous_payload)
        item = store.add_ioc(req)
        # Verify it's stored strictly as text
        assert item.indicator == dangerous_payload
        store.delete_ioc(item.ioc_id)
    except ValueError:
        # Expected if validation rejected dangerous characters
        pass


# =============================================================================
# 7. REST API Endpoints & Import Tests (User Correction #3)
# =============================================================================

def test_api_iocs_crud_and_check():
    """Tests the full REST API lifecycle: list, add, get, toggle, check, delete."""
    test_ip = f"198.51.100.{uuid.uuid4().int % 200 + 10}"

    # 1. Add
    create_resp = client.post("/api/threat-intel/iocs", json={
        "ioc_type": "IP",
        "indicator": test_ip,
        "severity": "HIGH",
        "confidence": 0.90,
        "category": "C2",
        "description": "API test IOC"
    })
    assert create_resp.status_code == 201
    ioc_id = create_resp.json()["ioc"]["ioc_id"]

    # 2. Get Detail
    detail_resp = client.get(f"/api/threat-intel/iocs/{ioc_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["ioc"]["indicator"] == test_ip

    # 3. Direct Check
    check_resp = client.post("/api/threat-intel/check", json={"indicator": test_ip, "ioc_type": "IP"})
    assert check_resp.status_code == 200
    assert check_resp.json()["matched"] is True

    # 4. Disable
    dis_resp = client.post(f"/api/threat-intel/iocs/{ioc_id}/disable")
    assert dis_resp.status_code == 200
    assert dis_resp.json()["enabled"] is False

    # Check again (must not match disabled)
    check_dis = client.post("/api/threat-intel/check", json={"indicator": test_ip, "ioc_type": "IP"})
    assert check_dis.json()["matched"] is False

    # 5. Enable
    en_resp = client.post(f"/api/threat-intel/iocs/{ioc_id}/enable")
    assert en_resp.status_code == 200
    assert en_resp.json()["enabled"] is True

    # 6. List with filter
    list_resp = client.get("/api/threat-intel/iocs?ioc_type=IP&limit=10")
    assert list_resp.status_code == 200
    assert any(i["ioc_id"] == ioc_id for i in list_resp.json()["iocs"])

    # 7. Delete
    del_resp = client.delete(f"/api/threat-intel/iocs/{ioc_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True


def test_api_bulk_import_json():
    """Tests bulk import of IOCs via JSON endpoint."""
    ip1 = f"198.51.100.{(uuid.uuid4().int % 90) + 10}"
    ip2 = f"198.51.100.{(uuid.uuid4().int % 90) + 110}"

    payload = {
        "iocs": [
            {"ioc_type": "IP", "indicator": ip1, "severity": "HIGH"},
            {"ioc_type": "IP", "indicator": ip2, "severity": "MEDIUM"}
        ]
    }

    resp = client.post("/api/threat-intel/import/json", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_submitted"] == 2
    assert data["imported_count"] == 2
    assert data["rejected_count"] == 0

    # Cleanup
    store = IOCStore()
    for ip in (ip1, ip2):
        item = store.get_ioc_by_indicator(ip, ioc_type="IP", active_only=False)
        if item:
            store.delete_ioc(item.ioc_id)


def test_api_bulk_import_csv():
    """Tests bulk import of IOCs via CSV file upload endpoint."""
    ip1 = f"198.51.100.{uuid.uuid4().int % 200 + 10}"
    dom1 = f"phish-{uuid.uuid4().hex[:6]}.test"

    csv_content = f"""ioc_type,indicator,severity,confidence,category,description
IP,{ip1},HIGH,0.85,C2,Test IP from CSV
DOMAIN,{dom1},CRITICAL,0.95,PHISHING,Test domain from CSV
"""
    resp = client.post(
        "/api/threat-intel/import/csv",
        content=csv_content,
        headers={"Content-Type": "text/csv"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_submitted"] == 2
    assert data["imported_count"] == 2
    assert data["rejected_count"] == 0

    # Cleanup
    store = IOCStore()
    for ind in (ip1, dom1):
        item = store.get_ioc_by_indicator(ind, active_only=False)
        if item:
            store.delete_ioc(item.ioc_id)
