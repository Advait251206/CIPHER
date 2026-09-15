"""
CIPHER Phase 6 — Correlation & Incident Response Demo
Safe, local-only demonstration of unified event correlation, attack escalation detection,
threat score bounding, and PreventionEngine integration.

Guarantees:
- Runs strictly on local test structures; NO live traffic sent to external systems.
- Respects detect_only mode (no host firewall modifications).
- Demonstrates:
  1. Sequential attack chain: PORT_SCAN -> BRUTE_FORCE -> DOS
  2. Potential attack escalation detection
  3. Strict identity separation (different destinations create separate incidents)
  4. Bounded correlation score (0-100)
  5. Incident lifecycle inspection
"""

import sys
import uuid
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Ensure repo root on path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.correlation.service import get_correlation_service


def run_demo():
    print("=" * 75)
    print("      CIPHER PHASE 6 — UNIFIED SECURITY EVENT CORRELATION DEMO")
    print("   Local-First • Bounded Correlation • Potential Attack Escalation")
    print("=" * 75)

    corr_svc = get_correlation_service()
    now = datetime.now(timezone.utc)

    source_ip = "127.0.0.1"
    target_ip = "127.0.0.1"

    print("\n[*] Scenario: Sequential Attacker Activity from 127.0.0.1 against 127.0.0.1")
    print("    Targeting internal service on port 8080.\n")

    # Step 1: Reconnaissance (PORT_SCAN)
    print("--- [Event 1: Reconnaissance] ---")
    ev1 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "event_type": "network_detection",
        "attack_type": "PORT_SCAN",
        "risk_score": 45,
        "confidence": 0.82,
        "source_ip": source_ip,
        "source_port": 51234,
        "destination_ip": target_ip,
        "destination_port": 8080,
        "protocol": "TCP",
        "recommendation": "High frequency SYN flags targeting closed ports."
    }
    inc1 = corr_svc.process_event(ev1)
    print(f"  Event Ingested: PORT_SCAN (Risk Score: 45)")
    print(f"  -> Correlated Incident ID: {inc1['incident_id']}")
    print(f"  -> Status: {inc1['status']} | Events: {inc1['event_count']}")
    print(f"  -> Correlation Score: {inc1['correlation_score']} | Severity: {inc1['severity']}")
    print(f"  -> Escalation Detected: {inc1['escalation_detected']}")
    print(f"  -> Applied Action: {inc1.get('applied_action')} (Mode: detect_only)\n")

    # Step 2: Credential Access (BRUTE_FORCE)
    print("--- [Event 2: Authentication Attack] ---")
    ev2 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=25)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "event_type": "network_detection",
        "attack_type": "BRUTE_FORCE",
        "risk_score": 68,
        "confidence": 0.88,
        "source_ip": source_ip,
        "source_port": 51235,
        "destination_ip": target_ip,
        "destination_port": 8080,
        "protocol": "TCP",
        "recommendation": "Multiple rapid authentication failures detected."
    }
    inc2 = corr_svc.process_event(ev2)
    print(f"  Event Ingested: BRUTE_FORCE (Risk Score: 68)")
    print(f"  -> Incident ID: {inc2['incident_id']} (Updated existing chain)")
    print(f"  -> Events: {inc2['event_count']} | Categories: {inc2['attack_categories']}")
    print(f"  -> Correlation Score: {inc2['correlation_score']} | Severity: {inc2['severity']}")
    print(f"  -> Escalation Detected: {inc2['escalation_detected']}")
    print(f"  -> Summary: {inc2['summary']}\n")

    # Step 3: Denial of Service (DOS)
    print("--- [Event 3: Disruptive Attack] ---")
    ev3 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=55)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "event_type": "network_detection",
        "attack_type": "DOS",
        "risk_score": 92,
        "confidence": 0.96,
        "source_ip": source_ip,
        "source_port": 51236,
        "destination_ip": target_ip,
        "destination_port": 8080,
        "protocol": "TCP",
        "recommendation": "High packet rate flood overwhelming buffer limits."
    }
    inc3 = corr_svc.process_event(ev3)
    print(f"  Event Ingested: DOS (Risk Score: 92)")
    print(f"  -> Incident ID: {inc3['incident_id']}")
    print(f"  -> Events: {inc3['event_count']} | Categories: {inc3['attack_categories']}")
    print(f"  -> Correlation Score: {inc3['correlation_score']} / 100 (Bounded)")
    print(f"  -> Severity: {inc3['severity']}")
    print(f"  -> Escalation Detected: {inc3['escalation_detected']}")
    print(f"  -> Summary: {inc3['summary']}")
    print(f"  -> Recommended Action: {inc3.get('recommended_action')}")
    print(f"  -> Applied Action: {inc3.get('applied_action')}\n")

    # Step 4: Verify Identity Separation (Different Destination)
    print("--- [Event 4: Activity targeting DIFFERENT Destination] ---")
    diff_target = "10.0.0.99"
    ev4 = {
        "event_id": str(uuid.uuid4()),
        "timestamp": (now + timedelta(seconds=65)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "network",
        "attack_type": "PORT_SCAN",
        "risk_score": 45,
        "confidence": 0.80,
        "source_ip": source_ip,
        "destination_ip": diff_target
    }
    inc4 = corr_svc.process_event(ev4)
    print(f"  Event from {source_ip} targeting {diff_target}")
    print(f"  -> Resulting Incident ID: {inc4['incident_id']}")
    print(f"  -> Merged with original incident? {'NO (Correct identity isolation)' if inc4['incident_id'] != inc3['incident_id'] else 'YES (Violation)'}")
    print(f"  -> Destination IP: {inc4['destination_ip']}\n")

    # Step 5: Overall Correlation Statistics
    print("--- [Correlation Statistics] ---")
    stats = corr_svc.get_correlation_stats()
    print(json.dumps(stats, indent=2))
    print("\n[+] Demonstration successfully completed.")


if __name__ == "__main__":
    run_demo()
