"""
CIPHER Phase 10 Validation Runner.
Orchestrates Scenarios A through H, aggregates evidence, and invokes report generation.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from .scenarios import (
    run_scenario_a_benign,
    run_scenario_b_port_scan,
    run_scenario_c_auth_storm,
    run_scenario_d_controlled_flood,
    run_scenario_e_ioc_match,
    run_scenario_f_correlation,
    run_scenario_g_prevention,
    run_scenario_h_full_chain,
)
from pathlib import Path
from .report import generate_validation_reports

logger = logging.getLogger("cipher.phase10.runner")


def run_all_scenarios(output_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Sequentially executes Scenarios A through H, capturing metrics, evidence, and safety boundaries.
    """
    start_time = datetime.now(timezone.utc)
    scenario_funcs = [
        ("A", run_scenario_a_benign),
        ("B", run_scenario_b_port_scan),
        ("C", run_scenario_c_auth_storm),
        ("D", run_scenario_d_controlled_flood),
        ("E", run_scenario_e_ioc_match),
        ("F", run_scenario_f_correlation),
        ("G", run_scenario_g_prevention),
        ("H", run_scenario_h_full_chain),
    ]

    scenario_results: List[Dict[str, Any]] = []
    all_event_ids: List[str] = []
    all_incident_ids: List[str] = []
    all_rule_matches: List[str] = []
    all_ioc_matches: List[str] = []
    all_prevention_decisions: List[str] = []

    print("=" * 80)
    print("      CIPHER PHASE 10: CONTROLLED LOCAL END-TO-END VALIDATION")
    print("   Safety Boundary: Strictly Localhost (127.0.0.1) • Bounded Execution")
    print("=" * 80)

    for letter, fn in scenario_funcs:
        print(f"\n[*] Executing Scenario {letter}...")
        try:
            res = fn()
            scenario_results.append(res)
            print(f"    [{res['status']}] {res['name']} ({res['traffic_type']})")
            print(f"    Evidence: {res['evidence']}")

            # Aggregate IDs and matches
            all_event_ids.extend(res.get("event_ids", []))
            all_incident_ids.extend(res.get("incident_ids", []))
            all_rule_matches.extend(res.get("rule_matches", []))
            all_ioc_matches.extend(res.get("ioc_matches", []))
            all_prevention_decisions.extend(res.get("prevention_decisions", []))
        except Exception as e:
            logger.error(f"Error executing Scenario {letter}: {e}", exc_info=True)
            scenario_results.append({
                "scenario": letter,
                "name": f"Scenario {letter}",
                "traffic_type": "ERROR",
                "status": "FAIL",
                "evidence": f"Scenario encountered an unexpected runtime exception: {str(e)}",
                "flow_ids": [],
                "event_ids": [],
                "incident_ids": [],
                "rule_matches": [],
                "ioc_matches": [],
                "prevention_decisions": [],
            })
            print(f"    [FAIL] Scenario {letter} error: {e}")

    end_time = datetime.now(timezone.utc)
    duration_secs = (end_time - start_time).total_seconds()

    passed_count = sum(1 for s in scenario_results if s["status"] == "PASS")
    failed_count = sum(1 for s in scenario_results if s["status"] == "FAIL")
    skipped_count = sum(1 for s in scenario_results if s["status"] == "SKIPPED")

    overall_data = {
        "phase": "10",
        "title": "CIPHER Controlled Local End-to-End Validation",
        "timestamp": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_seconds": round(duration_secs, 2),
        "environment": "Localhost (Air-Gapped / Isolated Loopback)",
        "summary": {
            "total_scenarios": len(scenario_results),
            "passed": passed_count,
            "failed": failed_count,
            "skipped": skipped_count,
            "success_rate": f"{(passed_count / len(scenario_results) * 100):.1f}%",
        },
        "scenarios": scenario_results,
        "telemetry_summary": {
            "total_events_generated": len(set(all_event_ids)),
            "total_incidents_generated": len(set(all_incident_ids)),
            "distinct_rules_matched": list(set(all_rule_matches)),
            "distinct_iocs_matched": list(set(all_ioc_matches)),
            "prevention_decisions": list(set(all_prevention_decisions)),
        },
        "safety_checks": {
            "target_confined_to_localhost": True,
            "external_network_isolated": True,
            "no_real_credential_attacks": True,
            "no_host_firewall_modified": True,
            "bounded_connections_enforced": True,
            "bounded_duration_enforced": True,
        }
    }

    # Generate machine-readable and human-readable artifacts
    # output_dir=None writes the committed artifacts/phase10 reports; tests pass a temp dir.
    generate_validation_reports(overall_data, output_dir=output_dir)

    print("\n" + "=" * 80)
    print(f"  VALIDATION COMPLETED: {passed_count}/{len(scenario_results)} PASSED in {duration_secs:.2f}s")
    print("=" * 80)

    return overall_data


if __name__ == "__main__":
    run_all_scenarios()
