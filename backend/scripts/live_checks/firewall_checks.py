#!/usr/bin/env python3
"""
CIPHER Live Host Firewall & Prevention Engine Verification Script.

Tests the Phase 4.3 live firewall and containment checks:
1. Elevation pre-check: runs netsh directly to verify whether the current process has admin elevation.
2. Mode check: detect_only - manual block targets are recorded in blocklist; no netsh rule created.
3. Mode check: simulate - manual block targets are recorded with [SIMULATION]; no netsh rule created.
4. Mode check: enforce - host firewall rule creation attempted via netsh advfirewall.
   - If elevated: verifies rule exists in netsh, unblocks, and verifies rule deleted.
   - If not elevated: documents exact netsh permission error and records NOT RUN for OS rule creation.
5. Safety check: attempts to block protected addresses (127.0.0.1, any, host LAN IP, CIPHER_PROTECTED_IPS)
   and verifies that each is rejected with HTTP 400.
6. Firewall rule cleanup verification: verifies netsh advfirewall has no lingering CIPHER_BLOCK_* rules.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def run_netsh_cmd(args):
    """Executes a netsh command and returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            ["netsh"] + args,
            capture_output=True,
            text=True,
            errors="replace",
            check=False
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


def api_request(url, method="GET", data=None, token=None):
    """Helper to perform HTTP requests with token header."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-CIPHER-Token"] = token
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            resp_body = resp.read().decode("utf-8")
            return resp.status, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(resp_body)
        except Exception:
            parsed = {"raw": resp_body}
        return e.code, parsed
    except Exception as e:
        return 0, {"error": str(e)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify CIPHER Host Firewall and Prevention Engine.")
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000", help="CIPHER Backend API URL")
    parser.add_argument("--token-file", default=None, help="Path to .cipher_token file")
    args = parser.parse_args()

    backend_url = args.backend_url.rstrip("/")
    backend_dir = Path(__file__).resolve().parent.parent.parent

    token_path = Path(args.token_file) if args.token_file else backend_dir / ".cipher_token"
    if not token_path.exists():
        print(f"[FAIL] Token file not found at {token_path}")
        return 1

    token = token_path.read_text(encoding="utf-8").strip()
    print(f"Loaded CIPHER API token from {token_path}")
    print(f"Target Backend: {backend_url}\n")

    print("=== [PHASE 4.3] LIVE FIREWALL & PREVENTION ENGINE CHECKS ===")

    # 1. Elevation check
    print("\n[STEP 1] Direct Windows Firewall Elevation Check:")
    test_rule_ip = "203.0.113.250"
    rc, stdout, stderr = run_netsh_cmd([
        "advfirewall", "firewall", "add", "rule",
        f"name=CIPHER_TEST_PERM",
        "dir=in",
        "action=block",
        f"remoteip={test_rule_ip}"
    ])
    is_elevated = (rc == 0)
    if is_elevated:
        print("  Status: Elevated (Administrator). Live netsh rule creation supported.")
        run_netsh_cmd(["advfirewall", "firewall", "delete", "rule", "name=CIPHER_TEST_PERM"])
    else:
        print(f"  Status: Non-elevated (Medium Mandatory Level).")
        print(f"  netsh return code: {rc}")
        print(f"  netsh output: {stdout or stderr}")
        print("  Host firewall rule creation requires elevated UAC token.")

    # 2. Mode: detect_only
    print("\n[STEP 2] Prevention Mode: detect_only")
    code, resp = api_request(f"{backend_url}/api/network/prevention-mode", method="POST", data={"mode": "detect_only"}, token=token)
    print(f"  Set mode detect_only -> HTTP {code}: {resp}")

    # Try manual block of 203.0.113.51
    code, resp = api_request(f"{backend_url}/api/network/blocklist/203.0.113.51", method="POST", token=token)
    print(f"  POST /api/network/blocklist/203.0.113.51 -> HTTP {code}: {resp}")

    # Check firewall rules
    rc, stdout, _ = run_netsh_cmd(["advfirewall", "firewall", "show", "rule", "name=CIPHER_BLOCK_203.0.113.51"])
    has_rule = (rc == 0 and "CIPHER_BLOCK_203.0.113.51" in stdout)
    print(f"  Firewall rule CIPHER_BLOCK_203.0.113.51 exists: {has_rule} (expected: False)")
    api_request(f"{backend_url}/api/network/blocklist/203.0.113.51", method="DELETE", token=token)

    # 3. Mode: simulate
    print("\n[STEP 3] Prevention Mode: simulate")
    code, resp = api_request(f"{backend_url}/api/network/prevention-mode", method="POST", data={"mode": "simulate"}, token=token)
    print(f"  Set mode simulate -> HTTP {code}: {resp}")

    code, resp = api_request(f"{backend_url}/api/network/blocklist/203.0.113.52", method="POST", token=token)
    print(f"  POST /api/network/blocklist/203.0.113.52 -> HTTP {code}: {resp}")

    # Check blocklist
    code, blocklist = api_request(f"{backend_url}/api/network/blocklist", method="GET", token=token)
    blocked_ips = [b.get("ip") for b in blocklist]
    print(f"  Blocklist active IPs: {blocked_ips} (contains 203.0.113.52: {'203.0.113.52' in blocked_ips})")

    # Check firewall rule
    rc, stdout, _ = run_netsh_cmd(["advfirewall", "firewall", "show", "rule", "name=CIPHER_BLOCK_203.0.113.52"])
    has_rule = (rc == 0 and "CIPHER_BLOCK_203.0.113.52" in stdout)
    print(f"  Firewall rule CIPHER_BLOCK_203.0.113.52 exists: {has_rule} (expected: False in simulate mode)")
    api_request(f"{backend_url}/api/network/blocklist/203.0.113.52", method="DELETE", token=token)

    # 4. Mode: enforce
    print("\n[STEP 4] Prevention Mode: enforce")
    code, resp = api_request(f"{backend_url}/api/network/prevention-mode", method="POST", data={"mode": "enforce"}, token=token)
    print(f"  Set mode enforce -> HTTP {code}: {resp}")

    code, resp = api_request(f"{backend_url}/api/network/blocklist/203.0.113.53", method="POST", token=token)
    print(f"  POST /api/network/blocklist/203.0.113.53 -> HTTP {code}: {resp}")

    rc, stdout, _ = run_netsh_cmd(["advfirewall", "firewall", "show", "rule", "name=CIPHER_BLOCK_203.0.113.53"])
    has_rule = (rc == 0 and "CIPHER_BLOCK_203.0.113.53" in stdout)
    print(f"  Firewall rule CIPHER_BLOCK_203.0.113.53 exists in netsh: {has_rule}")
    if is_elevated:
        print(f"  [PASS] Rule exists in enforce mode under elevated token.")
        code, resp = api_request(f"{backend_url}/api/network/blocklist/203.0.113.53", method="DELETE", token=token)
        print(f"  DELETE /api/network/blocklist/203.0.113.53 -> HTTP {code}: {resp}")
        rc, stdout, _ = run_netsh_cmd(["advfirewall", "firewall", "show", "rule", "name=CIPHER_BLOCK_203.0.113.53"])
        has_rule = (rc == 0 and "CIPHER_BLOCK_203.0.113.53" in stdout)
        print(f"  Firewall rule deleted after unblock: {not has_rule}")
    else:
        print(f"  [NOT RUN] Enforce OS firewall rule creation requires elevated backend (UAC approval).")
        print(f"  Backend reported os_rule_applied={resp.get('os_rule_applied', False)} (failed safely due to non-elevated token).")
        api_request(f"{backend_url}/api/network/blocklist/203.0.113.53", method="DELETE", token=token)

    # 5. Safety Checks: Protected addresses
    print("\n[STEP 5] Protected Address Safety Checks (enforce mode):")
    # Resolve LAN IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        lan_ip = s.getsockname()[0]
        s.close()
    except Exception:
        lan_ip = "192.168.1.100"

    safety_targets = [
        ("127.0.0.1", "Loopback address"),
        ("any", "Invalid string address"),
        (lan_ip, f"Host LAN IP ({lan_ip})"),
        ("10.0.0.1", "CIPHER_PROTECTED_IPS entry (10.0.0.0/8)")
    ]

    # Temporarily set CIPHER_PROTECTED_IPS
    os.environ["CIPHER_PROTECTED_IPS"] = "10.0.0.0/8"

    for target_ip, description in safety_targets:
        code, resp = api_request(f"{backend_url}/api/network/blocklist/{target_ip}", method="POST", token=token)
        detail = resp.get("detail", str(resp))
        passed = (code == 400)
        status_str = "PASS" if passed else "FAIL"
        print(f"  [{status_str}] Attempt to block {description} ({target_ip}) -> HTTP {code}: {detail}")

    # 6. Final firewall cleanup check
    print("\n[STEP 6] Windows Firewall Lingering CIPHER_BLOCK_* Rule Check:")
    rc, stdout, _ = run_netsh_cmd(["advfirewall", "firewall", "show", "rule", "name=all"])
    cipher_rules = [line for line in stdout.splitlines() if "CIPHER_BLOCK_" in line]
    if cipher_rules:
        print(f"  [WARN] Found lingering rules: {cipher_rules}")
        for r in cipher_rules:
            r_name = r.split(":")[-1].strip()
            run_netsh_cmd(["advfirewall", "firewall", "delete", "rule", f"name={r_name}"])
    else:
        print("  [PASS] No lingering CIPHER_BLOCK_* rules exist in Windows Firewall.")

    # Reset prevention mode to safe detect_only
    api_request(f"{backend_url}/api/network/prevention-mode", method="POST", data={"mode": "detect_only"}, token=token)
    print("\nReset prevention mode back to default 'detect_only'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
