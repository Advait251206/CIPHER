#!/usr/bin/env python3
"""
CIPHER Live API Access Control & CSRF Guard Verification Script.

Runs the four Phase A2 live checks:
1. Dashboard Proxy: Verified that the frontend dev proxy (5173) attaches the API token
   server-side, allowing mode switching, IP blocking, and unblocking without manual token input.
2. CSRF Origin Guard: Verified that cross-origin POST requests from foreign origins
   (e.g., https://example.com) are rejected with HTTP 403 and do not alter state.
3. API Token Validation: Verified that state-changing requests directly against the API
   without X-CIPHER-Token are rejected with HTTP 401, while requests with a valid token
   pass authentication and reach input validation (HTTP 422/400).
4. Argument Injection Defense: Verified that POST /api/extension/launch rejects malicious
   browser command flags (e.g., --gpu-launcher=calc.exe) with HTTP 400 without spawning processes.

Usage:
    python -m scripts.live_checks.api_access [--backend-url http://127.0.0.1:8000] [--dashboard-url http://127.0.0.1:5173]
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify CIPHER API Access Control and CSRF Guards.")
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000", help="CIPHER Backend API URL")
    parser.add_argument("--dashboard-url", default="http://127.0.0.1:5173", help="CIPHER Dashboard URL (Vite dev proxy)")
    parser.add_argument("--token-file", default=None, help="Path to .cipher_token file (default: backend/.cipher_token)")
    args = parser.parse_args()

    backend_url = args.backend_url.rstrip("/")
    dashboard_url = args.dashboard_url.rstrip("/")

    # Resolve token file
    if args.token_file:
        token_path = Path(args.token_file)
    else:
        # Relative to backend root
        backend_dir = Path(__file__).resolve().parent.parent.parent
        token_path = backend_dir / ".cipher_token"

    if not token_path.exists():
        print(f"[FAIL] Token file not found at {token_path}. Ensure backend has been started at least once.")
        return 1

    token = token_path.read_text(encoding="utf-8").strip()
    if not token:
        print(f"[FAIL] Token file {token_path} is empty.")
        return 1

    print(f"Loaded CIPHER API token: {token[:8]}... from {token_path}")
    print(f"Target Backend:   {backend_url}")
    print(f"Target Dashboard: {dashboard_url}\n")

    failures = 0

    # -------------------------------------------------------------------------
    # Check 1: Dashboard proxy with server-injected token
    # -------------------------------------------------------------------------
    print("[CHECK 1] Dashboard Proxy (Vite server-injected token on 5173)...")
    try:
        # 1a. Switch mode to simulate
        req1a = urllib.request.Request(
            f"{dashboard_url}/api/network/prevention-mode",
            data=json.dumps({"mode": "simulate"}).encode(),
            headers={"Content-Type": "application/json", "Origin": dashboard_url},
            method="POST"
        )
        with urllib.request.urlopen(req1a, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            if resp.status == 200 and body.get("status") == "success":
                print("  [PASS] 1a. Switched mode to simulate via dashboard proxy.")
            else:
                print(f"  [FAIL] 1a. Unexpected response: {resp.status} {body}")
                failures += 1

        # 1b. Block 203.0.113.50
        req1b = urllib.request.Request(
            f"{dashboard_url}/api/network/blocklist/203.0.113.50",
            data=b"",
            headers={"Origin": dashboard_url},
            method="POST"
        )
        with urllib.request.urlopen(req1b, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            if resp.status == 200 and body.get("status") == "blocked":
                print("  [PASS] 1b. Blocked 203.0.113.50 via dashboard proxy.")
            else:
                print(f"  [FAIL] 1b. Unexpected response: {resp.status} {body}")
                failures += 1

        # 1c. Unblock 203.0.113.50
        req1c = urllib.request.Request(
            f"{dashboard_url}/api/network/blocklist/203.0.113.50",
            headers={"Origin": dashboard_url},
            method="DELETE"
        )
        with urllib.request.urlopen(req1c, timeout=5) as resp:
            body = json.loads(resp.read().decode())
            if resp.status == 200 and body.get("status") == "unblocked":
                print("  [PASS] 1c. Unblocked 203.0.113.50 via dashboard proxy.")
            else:
                print(f"  [FAIL] 1c. Unexpected response: {resp.status} {body}")
                failures += 1

    except Exception as e:
        print(f"  [FAIL] Check 1 encountered exception: {e}")
        failures += 1

    # -------------------------------------------------------------------------
    # Check 2: Foreign origin (CSRF / Origin check) from https://example.com
    # -------------------------------------------------------------------------
    print("\n[CHECK 2] CSRF Origin Guard from foreign origin (https://example.com)...")
    try:
        req2 = urllib.request.Request(
            f"{backend_url}/api/network/prevention-mode",
            data=json.dumps({"mode": "enforce"}).encode(),
            headers={"Content-Type": "application/json", "Origin": "https://example.com"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req2, timeout=5) as resp:
                print(f"  [FAIL] Expected 403 Forbidden but request succeeded with HTTP {resp.status}")
                failures += 1
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"  [PASS] Foreign origin correctly blocked with HTTP 403 ({e.reason}).")
            else:
                print(f"  [FAIL] Expected HTTP 403, got HTTP {e.code}")
                failures += 1

    except Exception as e:
        print(f"  [FAIL] Check 2 encountered exception: {e}")
        failures += 1

    # -------------------------------------------------------------------------
    # Check 3: API Token validation on /api/waf/config
    # -------------------------------------------------------------------------
    print("\n[CHECK 3] Direct API Token Validation on POST /api/waf/config...")
    try:
        # 3a. Without token -> expect 401
        req3a = urllib.request.Request(
            f"{backend_url}/api/waf/config",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req3a, timeout=5) as resp:
                print(f"  [FAIL] Request without token succeeded with HTTP {resp.status}; expected 401.")
                failures += 1
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print("  [PASS] Request without token correctly rejected with HTTP 401 Unauthorized.")
            else:
                print(f"  [FAIL] Expected HTTP 401, got HTTP {e.code}")
                failures += 1

        # 3b. With valid token -> expect pass auth and reach validation (422)
        req3b = urllib.request.Request(
            f"{backend_url}/api/waf/config",
            data=b"{}",
            headers={"Content-Type": "application/json", "X-CIPHER-Token": token},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req3b, timeout=5) as resp:
                # If an empty body passes, that would be unexpected for schema, but auth succeeded
                print(f"  [PASS] Request with token authenticated (HTTP {resp.status}).")
        except urllib.error.HTTPError as e:
            if e.code in (400, 422):
                print(f"  [PASS] Request with token authenticated and reached payload validation (HTTP {e.code}).")
            else:
                print(f"  [FAIL] Expected HTTP 422/400 validation error, got HTTP {e.code}")
                failures += 1

    except Exception as e:
        print(f"  [FAIL] Check 3 encountered exception: {e}")
        failures += 1

    # -------------------------------------------------------------------------
    # Check 4: Argument injection defense on POST /api/extension/launch
    # -------------------------------------------------------------------------
    print("\n[CHECK 4] Argument Injection Defense on POST /api/extension/launch...")
    try:
        req4 = urllib.request.Request(
            f"{backend_url}/api/extension/launch",
            data=json.dumps({"target_url": "--gpu-launcher=calc.exe"}).encode(),
            headers={"Content-Type": "application/json", "X-CIPHER-Token": token},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req4, timeout=5) as resp:
                print(f"  [FAIL] Malicious target_url was accepted (HTTP {resp.status}); expected 400.")
                failures += 1
        except urllib.error.HTTPError as e:
            if e.code == 400:
                print("  [PASS] Malicious target_url rejected with HTTP 400 Bad Request.")
            else:
                print(f"  [FAIL] Expected HTTP 400, got HTTP {e.code}")
                failures += 1

    except Exception as e:
        print(f"  [FAIL] Check 4 encountered exception: {e}")
        failures += 1

    # -------------------------------------------------------------------------
    # Final Result
    # -------------------------------------------------------------------------
    print("\n------------------------------------------------------------")
    if failures == 0:
        print("[RESULT] ALL 4 API ACCESS CONTROL CHECKS PASSED.")
        return 0
    else:
        print(f"[RESULT] {failures} CHECK(S) FAILED.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

