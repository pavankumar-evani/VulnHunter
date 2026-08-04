#!/usr/bin/env python3
"""
Merges the bulk real-CVE fixture files (remediation/sample-data/bulk/*, produced by
generate_bulk_findings.py) into remediation/output/normalized-findings.json.

This applies the EXACT same normalization rules documented in
.claude/agents/vuln-ingest-normalizer.md (asset.type classification, remediation_domain
assignment, stable IDs) as a plain script instead of an LLM subagent invocation - at
the ~3,000-finding scale this produces, running the real subagent once per record (or
even once per file) isn't tractable, and the classification rules are fully
deterministic/documented, not a judgment call that needs re-deriving each time (the
FIND-15 case earlier in this project's history already proved the subagent and these
exact rules agree). See that file's docstring for the source rules this mirrors.

Unlike a real third-party Tenable/Armis export, each bulk file here was generated with
full foreknowledge of its own category (see generate_bulk_findings.py), so asset.type
is derived directly from which file a row came from - no free-text inference needed,
which is what removes the ambiguity an LLM subagent would otherwise have to resolve
per-row.

Existing FIND-1..FIND-N entries in normalized-findings.json are preserved byte-for-byte
(matched by source + source_ref, never re-numbered) - only genuinely new records from
the bulk files get new sequential IDs, exactly matching the normalizer's stable-ID rule.
"""
import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BULK_DIR = Path(__file__).resolve().parent / "bulk"
OUTPUT_PATH = REPO_ROOT / "remediation" / "output" / "normalized-findings.json"

# filename stem -> asset.type, per vuln-ingest-normalizer.md's documented classification
# rules (each bulk file was generated already knowing which category it represents).
FILE_TO_ASSET_TYPE = {
    "tenable_bulk_os_windows": "windows-server",
    "tenable_bulk_os_linux": "unix-server",
    "tenable_bulk_network": "network-routing-switching",
    "tenable_bulk_network_security": "network-security-device",
    "tenable_bulk_cloud": "cloud-infrastructure",
    "tenable_bulk_certificate": "certificate",
    "tenable_bulk_sca": "application",
    "tenable_bulk_dast": "application",
}

# Only these two domains have a working remediation-fixer subagent today - same rule
# vuln-ingest-normalizer.md documents for every other asset type.
_REMEDIATION_DOMAIN_SUPPORTED = {"windows-server", "unix-server"}


def _remediation_domain(asset_type):
    return asset_type if asset_type in _REMEDIATION_DOMAIN_SUPPORTED else None


def _parse_tenable_csv(path, asset_type):
    findings = []
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            cve = row["CVE"] or None
            cvss = float(row["CVSS v3.0 Base Score"]) if row["CVSS v3.0 Base Score"] else None
            findings.append({
                "source": "tenable",
                "source_ref": row["Plugin ID"],
                "asset": {
                    "name": row["Host"],
                    "ip": row["IP Address"],
                    "type": asset_type,
                    "os": row["OS"],
                },
                "title": row["Name"],
                "cve": cve,
                "cvss": cvss,
                "severity": row["Risk"],
                "description": row["Synopsis"],
                "recommended_fix": row["Solution"],
                "remediation_domain": _remediation_domain(asset_type),
                "first_seen": row["First Discovered"],
                "last_seen": row["Last Observed"],
            })
    return findings


def _parse_armis_bulk(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for device in data["devices"]:
        for alert in device["alerts"]:
            findings.append({
                "source": "armis",
                "source_ref": str(device["deviceId"]),
                "asset": {
                    "name": device["deviceName"],
                    "ip": device["ipAddress"],
                    "type": "iot-ot-device",
                    "os": device["deviceType"],
                },
                "title": alert["title"],
                "cve": alert.get("cve"),
                "cvss": None,
                "severity": device["riskLevel"],
                "description": alert["description"],
                "recommended_fix": alert.get("recommendedFix")
                    or "Apply the vendor's security update for the affected firmware/software version, "
                       "or isolate the device on a segmented network/VLAN if no patch is currently available.",
                "remediation_domain": None,
                "first_seen": alert["firstSeen"][:10],
                "last_seen": alert["lastSeen"][:10],
            })
    return findings


def load_bulk_findings():
    all_new = []
    for csv_path in sorted(BULK_DIR.glob("tenable_bulk_*.csv")):
        asset_type = FILE_TO_ASSET_TYPE.get(csv_path.stem)
        if not asset_type:
            print(f"  skipping unrecognized bulk file: {csv_path.name}")
            continue
        rows = _parse_tenable_csv(csv_path, asset_type)
        print(f"  {csv_path.name}: {len(rows)} findings -> asset.type={asset_type}")
        all_new.extend(rows)

    armis_path = BULK_DIR / "armis_bulk_ot.json"
    if armis_path.exists():
        rows = _parse_armis_bulk(armis_path)
        print(f"  {armis_path.name}: {len(rows)} findings -> asset.type=iot-ot-device")
        all_new.extend(rows)

    return all_new


def merge(existing, new_findings):
    """Stable-ID merge: keep every existing finding exactly as-is (matched by
    source+source_ref), only assign new sequential FIND-N ids to genuinely new
    records, continuing from the current highest id."""
    existing_keys = {(f["source"], f["source_ref"]) for f in existing}
    next_id = max((int(f["id"].split("-")[1]) for f in existing), default=0) + 1

    merged = list(existing)
    added = 0
    for f in new_findings:
        key = (f["source"], f["source_ref"])
        if key in existing_keys:
            continue  # already present - stable-ID rule, never duplicate or renumber
        f = dict(f)
        f["id"] = f"FIND-{next_id}"
        f["kev"] = None
        f["epss"] = None
        merged.append(f)
        existing_keys.add(key)
        next_id += 1
        added += 1
    return merged, added


def main():
    existing = json.loads(OUTPUT_PATH.read_text(encoding="utf-8")) if OUTPUT_PATH.exists() else []
    print(f"Existing findings: {len(existing)}")

    print("Parsing bulk fixture files:")
    new_findings = load_bulk_findings()

    merged, added = merge(existing, new_findings)
    OUTPUT_PATH.write_text(json.dumps(merged, indent=2), encoding="utf-8")

    print(f"\nAdded {added} new findings (of {len(new_findings)} parsed - the rest already existed).")
    print(f"Total findings now: {len(merged)}")
    print(f"Written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
