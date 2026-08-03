#!/usr/bin/env python3
"""
Fetches live Tenable/Armis data and writes it into remediation/live-data/ in the exact
same file shapes as remediation/sample-data/ - so vuln-ingest-normalizer.md's ingestion
logic needs zero changes to consume real data instead of the samples.

Usage:
    python remediation/connectors/fetch_live_data.py --source tenable
    python remediation/connectors/fetch_live_data.py --source armis
    python remediation/connectors/fetch_live_data.py --source all

Credentials are read from environment variables, never from command-line arguments
(arguments can leak into shell history/process listings):
    TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
    ARMIS_SECRET_KEY, ARMIS_BASE_URL

Then run /remediate against the live files, e.g.:
    /remediate remediation/live-data/tenable_export.csv remediation/live-data/armis_export.json
"""
import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LIVE_DATA_DIR = REPO_ROOT / "remediation" / "live-data"

sys.path.insert(0, str(REPO_ROOT))

from remediation.connectors.tenable_connector import TenableConnector  # noqa: E402
from remediation.connectors.armis_connector import ArmisConnector  # noqa: E402


def fetch_tenable():
    access_key = os.environ.get("TENABLE_ACCESS_KEY")
    secret_key = os.environ.get("TENABLE_SECRET_KEY")
    if not access_key or not secret_key:
        print("error: set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY to fetch Tenable data", file=sys.stderr)
        return False
    conn = TenableConnector(access_key, secret_key)
    out_path = LIVE_DATA_DIR / "tenable_export.csv"
    print(f"Fetching live Tenable vulnerability export -> {out_path}")
    print("This calls the real Tenable.io API and may take several minutes.")
    conn.fetch_and_write_csv(out_path)
    print(f"Wrote {out_path}")
    return True


def fetch_armis():
    secret_key = os.environ.get("ARMIS_SECRET_KEY")
    base_url = os.environ.get("ARMIS_BASE_URL")
    if not secret_key or not base_url:
        print("error: set ARMIS_SECRET_KEY and ARMIS_BASE_URL to fetch Armis data", file=sys.stderr)
        return False
    conn = ArmisConnector(secret_key, base_url=base_url)
    out_path = LIVE_DATA_DIR / "armis_export.json"
    print(f"Fetching live Armis alerts -> {out_path}")
    print("This calls the real Armis API.")
    conn.fetch_and_write_json(out_path)
    print(f"Wrote {out_path}")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=["tenable", "armis", "all"], required=True)
    args = parser.parse_args()

    LIVE_DATA_DIR.mkdir(parents=True, exist_ok=True)

    ok = True
    if args.source in ("tenable", "all"):
        ok = fetch_tenable() and ok
    if args.source in ("armis", "all"):
        ok = fetch_armis() and ok

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
