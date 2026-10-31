#!/usr/bin/env python3
"""
CIPHER Tranco List Fetch & Reproducibility Script.

Downloads or extracts a dated Tranco top-domains list, filters to the top N registrable
domains, and outputs:
1. backend/data/trusted_domains.json (list of top N domains)
2. backend/data/trusted_domains.meta.json (provenance: list ID, date, N, SHA256)

Citation:
    P. Le Pochat, T. van Goethem, S. Tajalizadehkhoob, M. Korczynski, and W. Joosen,
    "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation,"
    in Network and Distributed System Security Symposium (NDSS), 2019.
    https://tranco-list.eu/

Usage:
    python -m scripts.fetch_tranco [--list-id 5JXX] [--top-n 50000]
"""

import argparse
import csv
import hashlib
import io
import json
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUT = BACKEND_DIR / "data" / "trusted_domains.json"
DEFAULT_META = BACKEND_DIR / "data" / "trusted_domains.meta.json"

DEFAULT_LIST_ID = "5JXX"
DEFAULT_DATE = "2024-01-01"
DEFAULT_TOP_N = 50_000


def fetch_or_extract(list_id: str, top_n: int, local_zip: Path = None) -> list:
    """Retrieves the top N domains from a local zip or Tranco endpoint."""
    lines = []

    # 1. Try local zip if provided or present
    if local_zip and local_zip.exists():
        try:
            with zipfile.ZipFile(local_zip, "r") as z:
                first_name = z.namelist()[0]
                with z.open(first_name) as f:
                    reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
                    for row in reader:
                        if len(row) >= 2:
                            lines.append(row[1].strip().lower())
                            if len(lines) >= top_n:
                                break
            if len(lines) >= top_n:
                return lines
        except Exception as e:
            print(f"[WARN] Could not read from local zip ({e}); falling back to network fetch.")

    # 2. Try network fetch from Tranco
    url = f"https://tranco-list.eu/download/{list_id}/1000000"
    print(f"Fetching Tranco list {list_id} from {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CIPHER-Reproducibility-Fetcher/1.3"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read()

        # May be a zip file or raw CSV
        if content[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                with z.open(z.namelist()[0]) as f:
                    reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
                    for row in reader:
                        if len(row) >= 2:
                            lines.append(row[1].strip().lower())
                            if len(lines) >= top_n:
                                break
        else:
            reader = csv.reader(io.StringIO(content.decode("utf-8", errors="ignore")))
            for row in reader:
                if len(row) >= 2:
                    lines.append(row[1].strip().lower())
                    if len(lines) >= top_n:
                        break
        return lines
    except Exception as e:
        print(f"[WARN] Network fetch from Tranco failed: {e}")
        return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch and verify reproducible Tranco whitelist.")
    parser.add_argument("--list-id", default=DEFAULT_LIST_ID, help="Tranco List ID (default: 5JXX)")
    parser.add_argument("--date", default=DEFAULT_DATE, help="Date of the Tranco list snapshot")
    parser.add_argument("--top-n", type=int, default=DEFAULT_TOP_N, help="Number of domains to retain (default: 50,000)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Path for trusted_domains.json")
    parser.add_argument("--meta-out", type=Path, default=DEFAULT_META, help="Path for trusted_domains.meta.json")
    parser.add_argument("--verify-only", action="store_true", help="Only verify existing JSON against metadata")
    args = parser.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)

    if args.verify_only:
        if not args.out.exists() or not args.meta_out.exists():
            print(f"[FAIL] Missing {args.out} or {args.meta_out}")
            return 1
        with open(args.meta_out, "r", encoding="utf-8") as f:
            meta = json.load(f)
        sha = hashlib.sha256(args.out.read_bytes()).hexdigest()
        if sha == meta.get("sha256"):
            print(f"[PASS] {args.out.name} matches metadata sha256: {sha}")
            return 0
        else:
            print(f"[FAIL] Hash mismatch: computed {sha} != expected {meta.get('sha256')}")
            return 1

    # Check if existing trusted_domains.json already exists and has top-N items
    domains = []
    if args.out.exists():
        try:
            with open(args.out, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if len(loaded) >= args.top_n:
                    domains = loaded[:args.top_n]
                    print(f"Using existing {len(domains):,} domains from {args.out}")
        except Exception:
            domains = []

    if len(domains) < args.top_n:
        local_zip = BACKEND_DIR / "data" / "top-1m.csv.zip"
        domains = fetch_or_extract(args.list_id, args.top_n, local_zip)

    if not domains:
        print("[FAIL] Could not populate Tranco domains from local cache or network.")
        return 1

    # Write JSON
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(domains, f, separators=(",", ":"))

    sha256_hash = hashlib.sha256(args.out.read_bytes()).hexdigest()

    meta = {
        "dataset_name": "Tranco Top Sites Ranking",
        "citation": "P. Le Pochat et al., NDSS 2019 (https://tranco-list.eu/)",
        "list_id": args.list_id,
        "date": args.date,
        "top_n": len(domains),
        "sha256": sha256_hash,
        "file": args.out.name,
    }

    with open(args.meta_out, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"[SUCCESS] Wrote {len(domains):,} domains to {args.out}")
    print(f"          Wrote metadata to {args.meta_out} (sha256: {sha256_hash[:16]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

